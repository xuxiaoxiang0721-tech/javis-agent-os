"""Transport projection ordering only; owner/signature and real graph have separate tests."""
import importlib.util,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

script=Path(__file__).with_name('control-panel.py')
if not script.exists():script=Path(__file__).parent.parent/'scripts/control-panel.py'
spec=importlib.util.spec_from_file_location('panel_projection',script);panel=importlib.util.module_from_spec(spec);spec.loader.exec_module(panel)

class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='javis-projection-adapter-test-');self.addCleanup(self.temp.cleanup)
        self.app=panel.App(self.temp.name)

    def test_confirmed_decision_projects_only_its_scope(self):
        with patch('memory_review.MemoryReview.review',return_value={'status':'confirmed','scope':'cards-master','command_id':'fixture'}) as review,patch('task_memory._graph',return_value={'status':'ok'}) as graph:
            out=self.app.review_memory(None,{},None)
            self.assertEqual(out['graph_projection']['status'],'ok');self.assertEqual(graph.call_args.args[1],['cards-master']);review.assert_called_once()

    def test_graph_outage_preserves_durable_confirmation(self):
        with patch('memory_review.MemoryReview.review',return_value={'status':'confirmed','scope':'invest'}),patch('task_memory._graph',return_value={'status':'pending','reason':'graph_unavailable_or_timeout'}):
            out=self.app.review_memory(None,{},None)
            self.assertEqual(out['status'],'confirmed');self.assertEqual(out['graph_projection']['status'],'pending')

    def test_unconfirmed_decision_never_projects(self):
        for status in ['rejected','pending_review']:
            with patch('memory_review.MemoryReview.review',return_value={'status':status,'scope':'cards-master'}),patch('task_memory._graph') as graph:
                out=self.app.review_memory(None,{},None);graph.assert_not_called();self.assertEqual(out['graph_projection']['status'],'not_applicable')

if __name__=='__main__':unittest.main(verbosity=2)
